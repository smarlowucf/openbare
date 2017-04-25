#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright © 2016 SUSE LLC, Robert Schweikert <rjschwei@suse.com>,
# James Mason <jmason@suse.com>.
#
# This file is part of openbare.
#
# openbare is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# openbare is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with openbare. If not, see <http://www.gnu.org/licenses/>.

import boto3
import json

from collections import defaultdict
from django.core.management.base import BaseCommand
from library.models import Lendable, Resource


def get_available_regions(service):
    """List available regions for service."""
    session = boto3.Session()
    return session.get_available_regions(service)


class Command(BaseCommand):
    help = 'Collect all resources for EC2 lendables.'

    def handle(self, *args, **options):
        collected = defaultdict(list)
        for region in ['us-west-2']:
            # Check all available cloudtrail regions for events
            MAX_RESULTS = 50
            cloud_trail = boto3.client('cloudtrail', region_name=region)
            event_triggers = [
                'CreateVolume',
                'RunInstances',
                'CreateImage',
                'CreateSnapshot'
            ]

            results_left = True
            token = None
            while results_left:
                # If results greater than 50 there will be pages
                # loop through each page until no next token.
                if token:
                    events = cloud_trail.lookup_events(
                        MaxResults=MAX_RESULTS,
                        NextToken=token
                    )
                else:
                    events = cloud_trail.lookup_events(
                        MaxResults=MAX_RESULTS
                    )

                if 'NextToken' in events:
                    token = events['NextToken']
                else:
                    token = None
                    results_left = False

                for event in events['Events']:
                    if event['EventName'] in event_triggers:
                        # If the event is in triggers list log it.
                        event_name = event['EventName']
                        detail = json.loads(event['CloudTrailEvent'])

                        region = detail['awsRegion']
                        # arn = detail['userIdentity']['arn']
                        principal = detail['userIdentity']['principalId']
                        user_type = detail['userIdentity']['type']

                        if user_type == 'Root':
                            # No openbare user exists to store
                            # root account events
                            continue

                        elif user_type == 'IAMUser':
                            user = detail['userIdentity']['userName']

                        else:
                            user = principal.split(':')[-1]

                        resource = {
                            'region': region,
                            'user': user,
                            'userType': user_type,
                            'principal': principal
                        }

                        if event_name == 'RunInstances':
                            items = (
                                detail['responseElements']
                                ['instancesSet']
                                ['items']
                            )
                            for item in items:
                                instance = dict(resource)
                                instance['id'] = item['instanceId']
                                instance['type'] = 'instance'
                                collected[user].append(instance)

                        else:
                            if event_name == 'CreateVolume':
                                resource['id'] = (
                                    detail['responseElements']['volumeId']
                                )
                                resource['type'] = 'vol'

                            elif event_name == 'CreateImage':
                                resource['id'] = (
                                    detail['responseElements']['imageId']
                                )
                                resource['type'] = 'image'

                            elif event_name == 'CreateSnapshot':
                                resource['id'] = (
                                    detail['responseElements']['snapshotId']
                                )
                                resource['type'] = 'snapshot'

                            collected[user].append(resource)

        for username, resources in collected.items():
            # import pdb;pdb.set_trace()
            lendable = Lendable.all_types.get(username=username)
            lendable_resources = []
            for resource in resources:
                lendable_resources.append(
                    Resource(
                        lendable=lendable,
                        region=resource['region'],
                        resource_type=resource['type'],
                        resource_id=resource['id']
                    )
                )
            lendable.resources.bulk_create(lendable_resources)
            self.stdout.write(
                self.style.SUCCESS(
                    'Logged %i resource(s) for lendable with username: %s'
                    % (len(lendable_resources), username)
                )
            )
